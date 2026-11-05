from backend.events import EventType, Outcome
from backend.synthetic import generate_bruteforce_scenario, generate_benign_scenario, generate_failed_bruteforce_scenario


def test_same_seed_gives_same_output():
    first_events, first_truth = generate_bruteforce_scenario(seed=42)
    second_events, second_truth = generate_bruteforce_scenario(seed=42)
    assert first_events == second_events
    assert first_truth == second_truth


def test_different_seed_changes_output():
    events_42, _ = generate_bruteforce_scenario(seed=42)
    events_7, _ = generate_bruteforce_scenario(seed=7)
    assert events_42 != events_7


def test_events_are_sorted_by_timestamp():
    events, _ = generate_bruteforce_scenario(seed=42)
    for previous, current in zip(events, events[1:]):
        assert previous.timestamp <= current.timestamp


def test_malicious_ids_exist_in_events():
    events, truth = generate_bruteforce_scenario(seed=42)
    generated_ids = {event.event_id for event in events}
    assert truth.malicious_event_ids
    for event_id in truth.malicious_event_ids:
        assert event_id in generated_ids


def test_scenario_contains_benign_events():
    events, truth = generate_bruteforce_scenario(seed=42)
    assert len(truth.malicious_event_ids) < len(events)


def test_attack_follows_causal_order():
    events, truth = generate_bruteforce_scenario(seed=42)
    malicious = [e for e in events if e.event_id in truth.malicious_event_ids]

    failures = [e for e in malicious if e.result is Outcome.FAILURE]
    success = next(e for e in malicious if e.result is Outcome.SUCCESS)
    sudo = next(e for e in malicious if e.event_type is EventType.SUDO)
    cron = next(e for e in malicious if e.event_type is EventType.CRON_CREATE)

    assert len(failures) >= 5
    assert all(f.timestamp < success.timestamp for f in failures)
    assert success.timestamp < sudo.timestamp < cron.timestamp

def test_failed_bruteforce_has_no_successful_login():
    events, truth = generate_failed_bruteforce_scenario(seed=42)
    
    malicious = [e for e in events if e.event_id in truth.malicious_event_ids]
    
    assert malicious
    assert all(e.result is Outcome.FAILURE for e in malicious)

def test_failed_bruteforce_claims_only_the_bruteforce_technique():
    events, truth = generate_failed_bruteforce_scenario(seed=42)
    assert truth.expected_techniques == ["T1110.001"]

def test_event_ids_never_collide_across_scenarios_or_seeds():
    """Ids land in one shared table, so they have to be unique there, not per scenario."""
    batches = [
        generate_bruteforce_scenario(seed=42)[0],
        generate_failed_bruteforce_scenario(seed=42)[0],
        generate_benign_scenario(seed=42)[0],
        generate_bruteforce_scenario(seed=7)[0],
    ]
    all_ids = [event.event_id for batch in batches for event in batch]
    assert len(all_ids) == len(set(all_ids))
