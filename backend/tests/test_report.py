from backend.detection import detect_bruteforce
from backend.report import Finding, IncidentReport, validate_report
from backend.synthetic import generate_bruteforce_scenario, generate_failed_bruteforce_scenario


def evidence_pool(events):
    return {event.event_id: event for event in events}


def build_report(findings, compromised=False, **overrides):
    defaults = dict(
        classification="true_positive",
        incident_type="successful_ssh_bruteforce",
        compromised=compromised,
        summary="ssh brute force",
        findings=findings,
        confidence="high",
    )
    return IncidentReport(**{**defaults, **overrides})


def test_report_grounded_in_observed_events_passes():
    events, truth = generate_bruteforce_scenario(seed=42)
    report = build_report(
        [Finding(statement="repeated failures", event_ids=truth.malicious_event_ids[:3])]
    )

    result = validate_report(report, evidence_pool(events))

    assert result.ok
    assert result.unsupported_claim_rate == 0.0


def test_invented_event_id_is_rejected():
    events, truth = generate_bruteforce_scenario(seed=42)
    report = build_report(
        [
            Finding(
                statement="made up evidence",
                event_ids=[truth.malicious_event_ids[0], "evt_9999"],
            )
        ]
    )

    result = validate_report(report, evidence_pool(events))

    assert not result.ok
    assert [v.kind for v in result.violations] == ["unknown_event"]
    assert result.unsupported_claim_rate == 0.5


def test_event_in_database_but_never_returned_by_a_tool_is_still_invented():
    events, truth = generate_bruteforce_scenario(seed=42)
    cited = truth.malicious_event_ids[0]
    pool = evidence_pool([e for e in events if e.event_id != cited])

    report = build_report([Finding(statement="unseen", event_ids=[cited])])

    assert [v.kind for v in validate_report(report, pool).violations] == ["unknown_event"]


def test_unknown_mitre_technique_is_rejected():
    events, truth = generate_bruteforce_scenario(seed=42)
    report = build_report(
        [
            Finding(
                statement="plausible nonsense",
                event_ids=truth.malicious_event_ids[:1],
                techniques=["T9999.999"],
            )
        ]
    )

    assert [v.kind for v in validate_report(report, evidence_pool(events)).violations] == [
        "unknown_technique"
    ]


def test_compromise_claim_needs_a_successful_login():
    """The failure mode the failed-bruteforce scenario exists to catch."""
    events, truth = generate_failed_bruteforce_scenario(seed=42)
    report = build_report(
        [Finding(statement="8 failed logins", event_ids=truth.malicious_event_ids)],
        compromised=True,
    )

    result = validate_report(report, evidence_pool(events))

    assert [v.kind for v in result.violations] == ["unsupported_compromise"]


def test_compromise_claim_passes_when_a_successful_login_is_cited():
    events, truth = generate_bruteforce_scenario(seed=42)
    alert = detect_bruteforce(events)[0]
    successful_login = next(
        e.event_id
        for e in events
        if e.event_id in truth.malicious_event_ids
        and e.event_id not in alert.event_ids
        and e.result.value == "success"
    )
    report = build_report(
        [Finding(statement="attacker got in", event_ids=[alert.event_ids[0], successful_login])],
        compromised=True,
    )

    assert validate_report(report, evidence_pool(events)).ok


def test_finding_without_evidence_is_impossible_to_build():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Finding(statement="trust me", event_ids=[])
