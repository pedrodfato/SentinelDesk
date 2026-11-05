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
    store_events,
    store_incidents,
)
from backend.detection import detect_bruteforce
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
        conn.execute("TRUNCATE events, incidents")
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
