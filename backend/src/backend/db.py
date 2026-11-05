"""Storage layer: schema, ingestion and the read queries the agent will use.

Plain SQL on purpose. These queries are the agent's evidence source, so they
stay readable and auditable rather than hidden behind an ORM.
"""

import hashlib
import os
from contextlib import contextmanager
from datetime import datetime

import psycopg
from dotenv import load_dotenv
from psycopg.rows import class_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from backend.detection import Alert
from backend.events import SecurityEvent
from psycopg.types.json import Json
from psycopg.rows import dict_row

load_dotenv()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    timestamp  TIMESTAMPTZ NOT NULL,
    host       TEXT NOT NULL,
    event_type TEXT NOT NULL,
    result     TEXT NOT NULL,
    username   TEXT,
    src_ip     TEXT,
    command    TEXT,
    raw        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events (timestamp);
CREATE INDEX IF NOT EXISTS events_src_ip_idx ON events (src_ip);
CREATE INDEX IF NOT EXISTS events_host_time_idx ON events (host, timestamp);
CREATE INDEX IF NOT EXISTS events_scenario_idx ON events (scenario_id, timestamp);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    host        TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    event_ids   TEXT[] NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id BIGSERIAL PRIMARY KEY,
    incident_id      TEXT NOT NULL REFERENCES incidents(incident_id),
    status           TEXT NOT NULL,
    report           JSONB,
    validation       JSONB,
    steps            JSONB NOT NULL,
    observed_event_ids TEXT[] NOT NULL,
    elapsed_ms       INT NOT NULL,
    model            TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Copy .env.example to .env.")
    return url


@contextmanager
def connect():
    with psycopg.connect(database_url()) as conn:
        yield conn


def init_schema() -> None:
    with connect() as conn:
        conn.execute(SCHEMA)


def incident_id_for(alert: Alert) -> str:
    """Derived from the alert, so re-ingesting the same alert cannot duplicate it.

    The evidence is part of the identity: rule, origin and start time alone
    collide across scenarios that share them, which silently merges unrelated
    incidents into one.

    Known ceiling: in a live feed, a later run that catches more failures for
    the same attack yields a different id. Fixing that needs incident merging,
    which the batch-ingest MVP does not have.
    """
    evidence = ",".join(sorted(alert.event_ids))
    fingerprint = (
        f"{alert.rule}|{alert.src_ip}|{alert.host}|{alert.first_seen.isoformat()}|{evidence}"
    )
    return "inc_" + hashlib.sha256(fingerprint.encode()).hexdigest()[:12]


def store_events(events: list[SecurityEvent]) -> int:
    """Insert events, skipping ones already stored. Returns how many were new."""
    with connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO events (event_id, scenario_id, timestamp, host, event_type, result,
                                username, src_ip, command, raw)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            [
                (
                    e.event_id,
                    e.scenario_id,
                    e.timestamp,
                    e.host,
                    e.event_type.value,
                    e.result.value,
                    e.username,
                    e.src_ip,
                    e.command,
                    e.raw,
                )
                for e in events
            ],
        )
        return cur.rowcount


def store_incidents(alerts: list[Alert]) -> list[str]:
    """Persist alerts as incidents. Returns every incident id, new or existing."""
    ids = []
    with connect() as conn, conn.cursor() as cur:
        for alert in alerts:
            incident_id = incident_id_for(alert)
            cur.execute(
                """
                INSERT INTO incidents (incident_id, rule, scenario_id, host, src_ip, event_ids,
                                       first_seen, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                (
                    incident_id,
                    alert.rule,
                    alert.scenario_id,
                    alert.host,
                    alert.src_ip,
                    alert.event_ids,
                    alert.first_seen,
                    alert.last_seen,
                ),
            )
            ids.append(incident_id)
    return ids


def events_by_ids(event_ids: list[str]) -> list[SecurityEvent]:
    with connect() as conn, conn.cursor(row_factory=class_row(SecurityEvent)) as cur:
        cur.execute(
            "SELECT * FROM events WHERE event_id = ANY(%s) ORDER BY timestamp",
            (event_ids,),
        )
        return cur.fetchall()


def events_in_window(
    scenario_id: str,
    start: datetime,
    end: datetime,
    host: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
    limit: int = 200,
) -> list[SecurityEvent]:
    """Time-boxed event search. This is the shape the agent's tools will call."""
    with connect() as conn, conn.cursor(row_factory=class_row(SecurityEvent)) as cur:
        cur.execute(
            """
            SELECT * FROM events
            WHERE scenario_id = %(scenario_id)s
              AND timestamp BETWEEN %(start)s AND %(end)s
              AND (%(host)s::text IS NULL OR host = %(host)s)
              AND (%(src_ip)s::text IS NULL OR src_ip = %(src_ip)s)
              AND (%(username)s::text IS NULL OR username = %(username)s)
            ORDER BY timestamp
            LIMIT %(limit)s
            """,
            {
                "scenario_id": scenario_id,
                "start": start,
                "end": end,
                "host": host,
                "src_ip": src_ip,
                "username": username,
                "limit": limit,
            },
        )
        return cur.fetchall()


class Incident(BaseModel):
    incident_id: str
    rule: str
    scenario_id: str
    host: str
    src_ip: str
    event_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    status: str


def list_incidents(limit: int = 50) -> list[Incident]:
    with connect() as conn, conn.cursor(row_factory=class_row(Incident)) as cur:
        cur.execute(
            """
            SELECT incident_id, rule, scenario_id, host, src_ip, event_ids, first_seen, last_seen, status
            FROM incidents ORDER BY first_seen DESC LIMIT %s
            """,
            (limit,),
        )
        return cur.fetchall()


def get_incident(incident_id: str) -> Incident | None:
    with connect() as conn, conn.cursor(row_factory=class_row(Incident)) as cur:
        cur.execute(
            """
            SELECT incident_id, rule, scenario_id, host, src_ip, event_ids, first_seen, last_seen, status
            FROM incidents WHERE incident_id = %s
            """,
            (incident_id,),
        )
        return cur.fetchone()


def store_investigation(investigation, model: str) -> int:
    """Persist one investigation run and return its id.

    No ON CONFLICT here, unlike events and incidents: re-investigating the same
    incident after a prompt change is the point, so every run is a new row and
    the table doubles as the audit trail.
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO investigations (incident_id, status, report, validation, steps,
                                        observed_event_ids, elapsed_ms, model)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING investigation_id
            """,
            (
                investigation.incident_id,
                investigation.status,
                Jsonb(investigation.report.model_dump(mode="json"))
                if investigation.report
                else None,
                Jsonb(investigation.validation.model_dump(mode="json"))
                if investigation.validation
                else None,
                Jsonb([step.model_dump(mode="json") for step in investigation.steps]),
                investigation.observed_event_ids,
                investigation.elapsed_ms,
                model,
            ),
        )
        return cur.fetchone()[0]

def latest_investigation(incident_id: str) -> dict | None:
    """Return the most recent investigation for an incident, or None if none exist."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT investigation_id, incident_id, status, report, validation, steps, observed_event_ids, elapsed_ms, model, created_at
            FROM investigations
            WHERE incident_id = %s
            ORDER BY investigation_id DESC
            LIMIT 1
            """,
            (incident_id,),
        )
        return cur.fetchone()