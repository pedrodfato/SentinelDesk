"""HTTP surface. Deliberately thin: every decision already lives in a layer below.

If a handler grows business logic, that logic belongs in detection, investigation
or db instead, where it is testable without a web server.
"""

from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend import db
from backend.events import SecurityEvent
from backend.investigation import Investigation, investigate
from backend.llm import DEFAULT_MODEL, GeminiModel

app = FastAPI(title="SentinelDesk", version="0.1.0")

# Named origins only. "*" in dev has a habit of surviving into production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class StoredInvestigation(Investigation):
    """A persisted run carries provenance the in-memory one does not have yet.

    Without these three the client cannot tell runs apart, show when one
    happened, or say which model produced it.
    """

    investigation_id: int
    model: str
    created_at: datetime


class IncidentDetail(BaseModel):
    incident: db.Incident
    events: list[SecurityEvent]


def _require_incident(incident_id: str) -> db.Incident:
    """404 once, here, instead of in every handler that looks one up."""
    incident = db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"no such incident: {incident_id}")
    return incident


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/incidents")
def get_incidents(limit: int = 50) -> list[db.Incident]:
    return db.list_incidents(limit=limit)


@app.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str) -> IncidentDetail:
    incident = _require_incident(incident_id)
    return IncidentDetail(incident=incident, events=db.events_by_ids(incident.event_ids))


@app.post("/incidents/{incident_id}/investigate")
def post_investigate(incident_id: str) -> Investigation:
    """Run an investigation now and store it.

    Known ceiling: this blocks for roughly 4-10s while the model works, holding a
    worker the whole time. Fine for one analyst, wrong for many. The upgrade is
    BackgroundTasks plus a status endpoint the client polls, which is not worth
    the moving parts until concurrent analysts exist.
    """
    _require_incident(incident_id)
    result = investigate(incident_id, GeminiModel())
    db.store_investigation(result, DEFAULT_MODEL)
    return result


@app.get("/incidents/{incident_id}/investigation")
def get_investigation(incident_id: str) -> StoredInvestigation:
    _require_incident(incident_id)
    row = db.latest_investigation(incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"no investigation for incident: {incident_id}")
    return row