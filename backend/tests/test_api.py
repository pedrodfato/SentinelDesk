"""Route-level checks.

Every bug this file exists to catch imported cleanly and served /docs happily:
a typo in a path, a response_model that quietly drops fields, a missing import
behind a schema. None of them surface until a route is actually called.
"""

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend import db
from backend.api import app
from backend.detection import detect_bruteforce
from backend.investigation import Investigation
from backend.synthetic import generate_bruteforce_scenario

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def seeded_database():
    try:
        db.init_schema()
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres unavailable: {exc}")
    with db.connect() as conn:
        conn.execute("TRUNCATE events, incidents, investigations")
    events, _ = generate_bruteforce_scenario(seed=42)
    db.store_events(events)
    db.store_incidents(detect_bruteforce(events))
    yield


@pytest.fixture
def incident_id():
    return db.list_incidents()[0].incident_id


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_every_route_matches_a_real_path(incident_id):
    """A typo in a path string still registers, serves /docs, and never matches.

    An unmatched route and a missing resource are both 404, so the body is what
    tells them apart: Starlette answers "Not Found", our handlers say why.
    """
    paths = [
        "/incidents",
        f"/incidents/{incident_id}",
        f"/incidents/{incident_id}/investigation",
    ]
    for path in paths:
        response = client.get(path)
        assert response.json() != {"detail": "Not Found"}, f"{path} matched no route"


def test_incident_detail_includes_its_events(incident_id):
    body = client.get(f"/incidents/{incident_id}").json()

    assert body["incident"]["incident_id"] == incident_id
    assert len(body["events"]) == len(body["incident"]["event_ids"])


def test_stored_investigation_keeps_its_provenance(incident_id):
    """response_model trims whatever it does not declare, silently and with a 200."""
    db.store_investigation(
        Investigation(incident_id=incident_id, status="incomplete", elapsed_ms=7),
        "fake-model",
    )

    body = client.get(f"/incidents/{incident_id}/investigation").json()

    assert body["model"] == "fake-model"
    assert body["investigation_id"]
    assert body["created_at"]


def test_unknown_incident_is_404():
    assert client.get("/incidents/inc_nope").status_code == 404
    assert client.get("/incidents/inc_nope/investigation").status_code == 404
    assert client.post("/incidents/inc_nope/investigate").status_code == 404


def test_cors_is_not_open_to_every_origin():
    response = client.get("/incidents", headers={"Origin": "https://evil.example"})
    assert response.headers.get("access-control-allow-origin") != "*"
