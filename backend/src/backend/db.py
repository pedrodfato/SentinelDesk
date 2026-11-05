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

from backend.detection import Alert
from backend.events import SecurityEvent

load_dotenv()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    host        TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    event_ids   TEXT[] NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
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
            INSERT INTO events (event_id, timestamp, host, event_type, result,
                                username, src_ip, command, raw)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            [
                (
                    e.event_id,
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
                INSERT INTO incidents (incident_id, rule, host, src_ip, event_ids,
                                       first_seen, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                (
                    incident_id,
                    alert.rule,
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
            WHERE timestamp BETWEEN %(start)s AND %(end)s
              AND (%(host)s::text IS NULL OR host = %(host)s)
              AND (%(src_ip)s::text IS NULL OR src_ip = %(src_ip)s)
              AND (%(username)s::text IS NULL OR username = %(username)s)
            ORDER BY timestamp
            LIMIT %(limit)s
            """,
            {
                "start": start,
                "end": end,
                "host": host,
                "src_ip": src_ip,
                "username": username,
                "limit": limit,
            },
        )
        return cur.fetchall()
