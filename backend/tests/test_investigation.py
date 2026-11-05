"""Loop behaviour, exercised with a scripted model so no API call is involved."""

import psycopg
import pytest

from backend import db
from backend.detection import detect_bruteforce
from backend.investigation import (
    Investigation,
    ModelTurn,
    ToolCall,
    investigate,
    parse_report,
)
from backend.report import TECHNIQUES, Finding, IncidentReport
from backend.synthetic import (
    generate_bruteforce_scenario,
    generate_failed_bruteforce_scenario,
)


class ScriptedModel:
    """Plays a fixed list of turns, so the loop is tested and not the model."""

    def __init__(self, turns: list[ModelTurn]):
        self.turns = list(turns)
        self.calls = 0
        self.last_conversation: list[dict] = []

    def next_turn(self, conversation, tools):
        self.calls += 1
        self.last_conversation = list(conversation)
        return self.turns.pop(0) if self.turns else ModelTurn()


def report_citing(event_ids, compromised=False, techniques=()):
    return IncidentReport(
        classification="true_positive",
        incident_type="successful_ssh_bruteforce",
        compromised=compromised,
        summary="brute force against web-01",
        findings=[
            Finding(
                statement="repeated failed logins from one source",
                event_ids=list(event_ids),
                techniques=list(techniques),
            )
        ],
        confidence="high",
    )


@pytest.fixture(scope="module", autouse=True)
def seeded_database():
    try:
        db.init_schema()
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres unavailable: {exc}")
    with db.connect() as conn:
        conn.execute("TRUNCATE events, incidents")
    events, _ = generate_bruteforce_scenario(seed=42)
    db.store_events(events)
    db.store_incidents(detect_bruteforce(events))
    yield


@pytest.fixture
def incident():
    return db.list_incidents()[0]


def test_alert_evidence_is_loaded_before_the_model_speaks(incident):
    model = ScriptedModel([ModelTurn(report=report_citing(incident.event_ids[:2]))])

    result = investigate(incident.incident_id, model)

    assert result.status == "complete"
    assert set(incident.event_ids) <= set(result.observed_event_ids)
    assert model.calls == 1


def test_tool_results_widen_the_evidence_pool(incident):
    model = ScriptedModel(
        [
            ModelTurn(
                tool_calls=[
                    ToolCall(
                        name="search_events",
                        args={
                            "start": "2026-11-05T09:00:00+00:00",
                            "end": "2026-11-05T12:00:00+00:00",
                            "host": incident.host,
                        },
                    )
                ]
            ),
            ModelTurn(report=report_citing(incident.event_ids[:1])),
        ]
    )

    result = investigate(incident.incident_id, model)

    assert result.status == "complete"
    assert result.steps[0].events_returned > len(incident.event_ids)
    assert len(result.observed_event_ids) > len(incident.event_ids)


def test_report_citing_unobserved_event_is_rejected(incident):
    model = ScriptedModel([ModelTurn(report=report_citing(["evt_does_not_exist"]))])

    result = investigate(incident.incident_id, model)

    assert result.status == "rejected"
    assert [v.kind for v in result.validation.violations] == ["unknown_event"]


def test_compromise_without_a_successful_login_is_rejected(incident):
    model = ScriptedModel([ModelTurn(report=report_citing(incident.event_ids, compromised=True))])

    result = investigate(incident.incident_id, model)

    assert result.status == "rejected"
    assert [v.kind for v in result.validation.violations] == ["unsupported_compromise"]


def test_loop_stops_at_the_step_limit(incident):
    endless = [
        ModelTurn(
            tool_calls=[
                ToolCall(
                    name="search_events",
                    args={"start": "2026-11-05T09:00:00+00:00", "end": "2026-11-05T10:00:00+00:00"},
                )
            ]
        )
        for _ in range(50)
    ]
    model = ScriptedModel(endless)

    result = investigate(incident.incident_id, model, max_steps=3)

    assert result.status == "incomplete"
    assert result.report is None
    assert len(result.steps) == 3


def test_tool_output_is_labelled_as_untrusted(incident):
    model = ScriptedModel(
        [
            ModelTurn(
                tool_calls=[
                    ToolCall(
                        name="lookup_technique", args={"technique_id": "T1110.001"}
                    )
                ]
            ),
            ModelTurn(report=report_citing(incident.event_ids[:1])),
        ]
    )

    investigate(incident.incident_id, model)

    tool_messages = [m for m in model.last_conversation if m["role"] == "tool"]
    assert tool_messages
    assert all("<untrusted_log_data>" in m["content"] for m in tool_messages)


def test_injected_instruction_in_a_log_field_stays_inside_the_data_block(incident):
    """The attacker-controlled username reaches the prompt, but only as quoted data."""
    model = ScriptedModel(
        [
            ModelTurn(
                tool_calls=[
                    ToolCall(
                        name="search_events",
                        args={
                            "start": "2026-11-05T09:00:00+00:00",
                            "end": "2026-11-05T12:00:00+00:00",
                        },
                    )
                ]
            ),
            ModelTurn(report=report_citing(incident.event_ids[:1])),
        ]
    )

    investigate(incident.incident_id, model)

    injected = [
        m for m in model.last_conversation if "ignore previous instructions" in m["content"]
    ]
    assert injected, "the scenario should carry the injection attempt"
    assert all(m["role"] == "tool" for m in injected)
    assert all(m["content"].startswith("<untrusted_log_data>") for m in injected)


def test_bad_model_output_does_not_crash_the_parser():
    assert parse_report("not json at all") is None
    assert parse_report({"classification": "nonsense"}) is None


def test_unknown_incident_is_an_error():
    with pytest.raises(LookupError):
        investigate("inc_nope", ScriptedModel([]))


def test_investigation_is_serialisable_for_storage(incident):
    model = ScriptedModel([ModelTurn(report=report_citing(incident.event_ids[:1]))])

    result = investigate(incident.incident_id, model)

    assert Investigation.model_validate_json(result.model_dump_json()) == result


def test_search_cannot_reach_another_scenarios_events(incident):
    """Scope comes from the incident. Two scenarios share hosts, ips and clock."""
    other_events, other_truth = generate_failed_bruteforce_scenario(seed=42)
    db.store_events(other_events)
    model = ScriptedModel(
        [
            ModelTurn(
                tool_calls=[
                    ToolCall(
                        name="search_events",
                        args={
                            "start": "2026-11-05T00:00:00+00:00",
                            "end": "2026-11-06T00:00:00+00:00",
                            "host": incident.host,
                        },
                    )
                ]
            ),
            ModelTurn(report=report_citing(incident.event_ids[:1])),
        ]
    )

    result = investigate(incident.incident_id, model)

    leaked = set(result.observed_event_ids) & {e.event_id for e in other_events}
    assert not leaked, f"investigation read {len(leaked)} events from another scenario"


def test_catalogue_is_discoverable_not_guessable(incident):
    """Attribution needs the catalogue in hand: lookup alone only confirms a guess."""
    model = ScriptedModel(
        [
            ModelTurn(tool_calls=[ToolCall(name="list_techniques", args={})]),
            ModelTurn(report=report_citing(incident.event_ids[:1])),
        ]
    )

    investigate(incident.incident_id, model)

    listed = [m for m in model.last_conversation if m["role"] == "tool"][0]["content"]
    assert all(technique in listed for technique in TECHNIQUES)
